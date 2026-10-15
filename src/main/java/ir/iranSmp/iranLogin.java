package ir.iranSmp;

import org.bukkit.ChatColor;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.*;
import org.bukkit.plugin.java.JavaPlugin;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public class iranLogin extends JavaPlugin implements Listener {

    private final Set<UUID> loggedIn = new HashSet<>();
    private final SecureRandom random = new SecureRandom();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        getServer().getPluginManager().registerEvents(this, this);

        getCommand("register").setExecutor((sender, command, label, args) -> {
            if (!(sender instanceof Player p)) return true;

            if (loggedIn.contains(p.getUniqueId())) {
                p.sendMessage("§aشما وارد شده‌اید!");
                return true;
            }

            if (args.length != 2) {
                p.sendMessage("§e/register <password> <password>");
                return true;
            }

            if (args[0].length() < 6 || !args[0].equals(args[1])) {
                p.sendMessage("§cرمزها باید یکسان و حداقل ۶ کاراکتر باشند.");
                return true;
            }

            String base = "users." + p.getUniqueId();
            if (getConfig().contains(base + ".hash")) {
                p.sendMessage("§cشما قبلاً ثبت‌نام کرده‌اید. از /login استفاده کنید.");
                return true;
            }

            byte[] salt = new byte[16];
            random.nextBytes(salt);
            String saltText = Base64.getEncoder().encodeToString(salt);

            try {
                String hash = hash(args[0].toCharArray(), salt);
                getConfig().set(base + ".salt", saltText);
                getConfig().set(base + ".hash", hash);
                saveConfig();

                loggedIn.add(p.getUniqueId());
                p.sendMessage("§aثبت‌نام موفق بود! خوش آمدی.");
            } catch (Exception e) {
                p.sendMessage("§cخطا در ثبت‌نام.");
                getLogger().warning("Password hashing failed.");
            } finally {
                Arrays.fill(args[0].toCharArray(), '\0');
                Arrays.fill(args[1].toCharArray(), '\0');
            }
            return true;
        });

        getCommand("login").setExecutor((sender, command, label, args) -> {
            if (!(sender instanceof Player p)) return true;

            if (loggedIn.contains(p.getUniqueId())) {
                p.sendMessage("§aشما قبلاً وارد شده‌اید!");
                return true;
            }

            String base = "users." + p.getUniqueId();
            if (args.length != 1 || !getConfig().contains(base + ".hash")) {
                p.sendMessage("§cابتدا ثبت‌نام کنید یا از /login <password> استفاده کنید.");
                return true;
            }

            try {
                byte[] salt = Base64.getDecoder().decode(
                    getConfig().getString(base + ".salt", ""));
                String hash = hash(args[0].toCharArray(), salt);

                if (hash.equals(getConfig().getString(base + ".hash"))) {
                    loggedIn.add(p.getUniqueId());
                    p.sendMessage("§aورود موفق بود! خوش آمدی.");
                } else {
                    p.sendMessage("§cرمز عبور اشتباه است.");
                }
            } catch (Exception e) {
                p.sendMessage("§cخطا در ورود.");
                getLogger().warning("Password verification failed.");
            }
            return true;
        });

        getCommand("iranlogin").setExecutor((sender, command, label, args) -> {
            sender.sendMessage("§6iranLogin §7- نسخه 1.0.0");
            sender.sendMessage("§e/login <password> §7- ورود");
            sender.sendMessage("§e/register <password> <password> §7- ثبت‌نام");
            return true;
        });

        getLogger().info("iranLogin enabled!");
    }

    private String hash(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 120000, 256);
        try {
            byte[] result = SecretKeyFactory
                .getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(result);
        } finally {
            spec.clearPassword();
            Arrays.fill(password, '\0');
        }
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player p = event.getPlayer();
        loggedIn.remove(p.getUniqueId());

        if (getConfig().contains("users." + p.getUniqueId() + ".hash")) {
            p.sendMessage("§6به iranSmp خوش آمدی! §e/login <password>");
        } else {
            p.sendMessage("§6به iranSmp خوش آمدی! §e/register <password> <password>");
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        loggedIn.remove(event.getPlayer().getUniqueId());
    }

    @EventHandler
    public void onMove(PlayerMoveEvent event) {
        if (!loggedIn.contains(event.getPlayer().getUniqueId())
                && event.getTo() != null
                && (event.getFrom().getBlockX() != event.getTo().getBlockX()
                || event.getFrom().getBlockY() != event.getTo().getBlockY()
                || event.getFrom().getBlockZ() != event.getTo().getBlockZ())) {
            event.setTo(event.getFrom());
        }
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        if (!loggedIn.contains(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage("§cابتدا وارد شوید یا ثبت‌نام کنید.");
        }
    }

    @EventHandler
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (loggedIn.contains(event.getPlayer().getUniqueId())) return;

        String message = event.getMessage().split(" ")[0].toLowerCase();
        if (!message.equals("/login")
                && !message.equals("/register")
                && !message.equals("/iranlogin")) {
            event.setCancelled(true);
            event.getPlayer().sendMessage("§cابتدا وارد شوید یا ثبت‌نام کنید.");
        }
    }
}
