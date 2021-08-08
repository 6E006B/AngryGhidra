package angryghidra;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import org.json.JSONArray;
import org.json.JSONObject;
import docking.ComponentProvider;
import docking.widgets.textfield.IntegerTextField;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

public class AngryGhidraProvider extends ComponentProvider {

    private JPanel panel;
    private JPanel CSOPanel;
    private JPanel SAPanel;
    static JTextArea textArea;
    private ArrayList < JButton > delButtons;
    private JSONObject angr_options;
    private Program ThisProgram;
    private String solution;
    private JSONObject solutionObject;
    private String insntrace;
    private String angrError;
    private Boolean isTerminated;
    private String TmpDir;
    private JScrollPane scroll;
    private ImageIcon addIcon;
    private ImageIcon delIcon;

    // Main Project Options Panel vars
    static JPanel MPOPanel;
    static JTextField TFBlankState;
    static JTextField TFFind;
    static JCheckBox chckbxBlankState;
    static JCheckBox chckbxAvoidAddresses;
    static JCheckBox chckbxAutoloadlibs;

    // Arguments Panel vars
    private IntegerTextField TFArglen;
    private JTextField TFArgsol;
    private int GuiArgCounter;
    private ArrayList < JButton > delArgs;
    private ArrayList < IntegerTextField > TFArgs;
    private ArrayList < JTextField > TFArgsSolutions;
    static JCheckBox chckbxArg;

    // Hook Panel vars
    static JPanel HookPanel;
    static ArrayList < JButton > delHooks;
    static ArrayList < JLabel > lbHooks;
    static int GuiHookCounter;
    static JPanel RegHookPanel;
    static Map < String[], String[][] > Hook;

    // CSO Panel vars
    private JPanel MemPanel;
    static JPanel WMPanel;
    private JPanel RegPanel;
    private ArrayList < JTextField > TFregs;
    private ArrayList < JTextField > TFVals;
    static ArrayList < IntegerTextField > TFStoreAddrs;
    static ArrayList < IntegerTextField > TFStoreVals;
    private ArrayList < JButton > delMem;
    static ArrayList < JButton > delStore;
    private JTextField TFVal1;
    static int GuiStoreCounter;
    private int GuiRegCounter;
    private int GuiMemCounter;
    static IntegerTextField TFstore_addr;
    static IntegerTextField TFstore_val;
    private IntegerTextField TFsymbmem_addr;
    private IntegerTextField TFsymbmem_len;
    private JTextField TFsymbmem_sol;
    private ArrayList < IntegerTextField > TFAddrs;
    private ArrayList < IntegerTextField > TFLens;
    private ArrayList < JTextField > TFSolutions;
    private JTextField TFReg1;
    private JButton btnAddWM;
    private JLabel lbStoreAddr;
    private JLabel lbStoreVal;
    private JLabel lblWriteToMemory;

    // Output Panel vars
    private JPanel OutputPanel;
    private ArrayList < JTextField > TFoutputFinds;
    private ArrayList < JTextField > TFoutputAvoids;
    private JTextField TFOutputFind1;
    private JTextField TFOutputAvoid1;
    private JTextArea OutputSolutionArea;
    private JScrollPane scrollOutputSolution;
    private int GuiOutputFindCounter;
    private int GuiOutputAvoidCounter;
    static JPanel OutputFindPanel;
    static JPanel OutputAvoidPanel;

    // Status Panel vars
    private JPanel EndPanel;
    private JLabel StatusLabel;
    private JLabel StatusLabelFound;
    private JLabel lbStatus;
    private JButton btnRun;
    private JButton btnStop;
    private JButton btnImport;
    private JButton btnExport;
    private JTextArea ErrorArea;
    private JScrollPane scrollError;
    private JTextArea ResultArea;
    private JScrollPane scrollResult;


    public AngryGhidraProvider(AngryGhidraPlugin plugin, String owner, Program program) {
        super(plugin.getTool(), owner, owner);
        setIcon(ResourceManager.loadImage("images/Ico.png"));
        setProgram(program);
        buildPanel();
    }

    private void buildMPOPanel() {
        MPOPanel = new JPanel();
        MPOPanel.setForeground(new Color(46, 139, 87));
        TitledBorder borderMPO = BorderFactory.createTitledBorder("Main project options");
        borderMPO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        MPOPanel.setBorder(borderMPO);

        chckbxAutoloadlibs = new JCheckBox("Auto load libs");
        chckbxAutoloadlibs.setFont(new Font("SansSerif", Font.PLAIN, 12));

        TFBlankState = new JTextField();
        TFBlankState.setVisible(false);
        TFBlankState.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (AngryGhidraPopupMenu.CurrentBlankAddr != null) {
                    AngryGhidraPopupMenu.UnSetColor(AngryGhidraPopupMenu.CurrentBlankAddr);
                    AngryGhidraPopupMenu.CurrentBlankAddr = null;
                }
            }
        });

        chckbxBlankState = new JCheckBox("Blank State");
        chckbxBlankState.setFont(new Font("SansSerif", Font.PLAIN, 12));
        chckbxBlankState.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxBlankState.isSelected()) {
                        TFBlankState.setVisible(true);
                    } else {
                        TFBlankState.setVisible(false);
                    }
                    MPOPanel.revalidate();
                }
            }
        );

        JLabel lbFind = new JLabel("Find address:");
        lbFind.setForeground(new Color(60, 179, 113));
        lbFind.setFont(new Font("SansSerif", Font.PLAIN, 12));

        TFFind = new JTextField();
        Font Classic_font = TFFind.getFont();
        TFFind.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (AngryGhidraPopupMenu.CurrentFindAddr != null) {
                    AngryGhidraPopupMenu.UnSetColor(AngryGhidraPopupMenu.CurrentFindAddr);
                    AngryGhidraPopupMenu.CurrentFindAddr = null;
                }
            }
        });

        chckbxAvoidAddresses = new JCheckBox("Avoid addresses");
        chckbxAvoidAddresses.setForeground(new Color(255, 0, 0));
        chckbxAvoidAddresses.setToolTipText("");
        chckbxAvoidAddresses.setFont(new Font("SansSerif", Font.PLAIN, 12));

        textArea = new JTextArea();
        textArea.setMinimumSize(new Dimension(40, 40));
        textArea.setToolTipText("Enter the hex values separated by comma.");
        textArea.setFont(Classic_font);
        textArea.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                if (AngryGhidraPopupMenu.CurrentAvoidAddrses.isEmpty() == false) {
                    try {
                        List < String > AvoidAddresses = Arrays.asList(textArea.getText().split("\\s*,\\s*"));
                        for (int i = 0; i < AngryGhidraPopupMenu.CurrentAvoidAddrses.size(); i++) {
                            String AddrfromGui = "0x" + AngryGhidraPopupMenu.CurrentAvoidAddrses.get(i).toString();
                            String AddrfromArea = AvoidAddresses.get(i);
                            if (AddrfromGui.equals(AddrfromArea) == false) {
                                AngryGhidraPopupMenu.UnSetColor(AngryGhidraPopupMenu.CurrentAvoidAddrses.get(i));
                                AngryGhidraPopupMenu.CurrentAvoidAddrses.remove(i);
                            }
                        }
                    } catch (Exception ex) {};
                }
            }
        });

        scroll = new JScrollPane(textArea);
        scroll.setMinimumSize(new Dimension(50, 50));
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        scroll.setVisible(false);
        chckbxAvoidAddresses.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxAvoidAddresses.isSelected()) {
                        scroll.setVisible(true);
                    } else {
                        scroll.setVisible(false);
                    }
                    MPOPanel.revalidate();
                }
            }
        );

        GroupLayout gl_MPOPanel = new GroupLayout(MPOPanel);
        gl_MPOPanel.setHorizontalGroup(
            gl_MPOPanel.createParallelGroup(Alignment.TRAILING)
            .addGroup(gl_MPOPanel.createSequentialGroup()
                .addGap(11)
                .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_MPOPanel.createSequentialGroup()
                        .addComponent(chckbxAutoloadlibs, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(105, Short.MAX_VALUE))
                    .addGroup(gl_MPOPanel.createSequentialGroup()
                        .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                                .addGroup(gl_MPOPanel.createSequentialGroup()
                                    .addComponent(chckbxBlankState, GroupLayout.DEFAULT_SIZE, 132, Short.MAX_VALUE)
                                    .addGap(18))
                                .addGroup(gl_MPOPanel.createSequentialGroup()
                                    .addComponent(chckbxAvoidAddresses, GroupLayout.PREFERRED_SIZE, 144, Short.MAX_VALUE)
                                    .addPreferredGap(ComponentPlacement.UNRELATED)))
                            .addGroup(gl_MPOPanel.createSequentialGroup()
                                .addGap(21)
                                .addComponent(lbFind, GroupLayout.PREFERRED_SIZE, 102, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(ComponentPlacement.RELATED)))
                        .addGroup(gl_MPOPanel.createParallelGroup(Alignment.LEADING)
                            .addComponent(TFBlankState, GroupLayout.DEFAULT_SIZE, 88, Short.MAX_VALUE)
                            .addComponent(TFFind, GroupLayout.DEFAULT_SIZE, 88, Short.MAX_VALUE)
                            .addComponent(scroll, GroupLayout.DEFAULT_SIZE, 88, Short.MAX_VALUE))
                        .addGap(15))))
        );
        gl_MPOPanel.setVerticalGroup(
            gl_MPOPanel.createParallelGroup(Alignment.LEADING)
            .addGroup(gl_MPOPanel.createSequentialGroup()
                .addGap(6)
                .addComponent(chckbxAutoloadlibs, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                .addGap(2)
                .addGroup(gl_MPOPanel.createParallelGroup(Alignment.BASELINE)
                    .addComponent(chckbxBlankState)
                    .addComponent(TFBlankState, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                .addGap(14)
                .addGroup(gl_MPOPanel.createParallelGroup(Alignment.BASELINE)
                    .addComponent(TFFind, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(lbFind, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(ComponentPlacement.UNRELATED)
                .addGroup(gl_MPOPanel.createParallelGroup(Alignment.BASELINE)
                    .addComponent(scroll, GroupLayout.DEFAULT_SIZE, 102, Short.MAX_VALUE)
                    .addComponent(chckbxAvoidAddresses, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        MPOPanel.setLayout(gl_MPOPanel);
    }

    private void buildArgumentsPanel() {
        SAPanel = new JPanel();
        SAPanel.setForeground(new Color(46, 139, 87));
        TitledBorder borderSA = BorderFactory.createTitledBorder("Program arguments");
        borderSA.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        SAPanel.setBorder(borderSA);

        chckbxArg = new JCheckBox("Arguments");
        chckbxArg.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JPanel ArgPanel = new JPanel();
        ArgPanel.setBorder(null);

        GroupLayout gl_SAPanel = new GroupLayout(SAPanel);
        gl_SAPanel.setHorizontalGroup(
            gl_SAPanel.createParallelGroup(Alignment.TRAILING)
            .addGroup(gl_SAPanel.createSequentialGroup()
                .addContainerGap()
                .addComponent(chckbxArg, GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
                .addGap(31)
                .addComponent(ArgPanel, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                .addContainerGap())
        );
        gl_SAPanel.setVerticalGroup(
            gl_SAPanel.createParallelGroup(Alignment.LEADING)
            .addGroup(gl_SAPanel.createSequentialGroup()
                .addGroup(gl_SAPanel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_SAPanel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(chckbxArg))
                    .addComponent(ArgPanel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(20))
        );

        GridBagLayout gbl_ArgPanel = new GridBagLayout();
        gbl_ArgPanel.columnWidths = new int[] {
            0,
            0,
            0
        };
        gbl_ArgPanel.rowHeights = new int[] {
            0,
            0,
            0
        };
        gbl_ArgPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_ArgPanel.rowWeights = new double[] {
            0.0,
            0.0,
            0.0
        };
        ArgPanel.setLayout(gbl_ArgPanel);

        JButton btnAddArg = addButtonToPanel(addIcon, ArgPanel, 0, 1);
        btnAddArg.setVisible(false);

        JLabel lbLenArg = addLabelToPanel("Length", ArgPanel, 1, 0);
        lbLenArg.setVisible(false);

        JLabel lbSolArg = addLabelToPanel("Solution", ArgPanel, 2, 0);
        lbSolArg.setVisible(false);

        TFArglen = addIntegerTextFieldtoPanel(ArgPanel, 1, 1);
        TFArglen.getComponent().setVisible(false);

        TFArgsol = addTextFieldToPanel(ArgPanel, 2, 1);
        TFArgsol.setVisible(false);
        TFArgsol.setEditable(false);
        TFArgsSolutions.add(TFArgsol);

        chckbxArg.addItemListener(
            new ItemListener() {
                public void itemStateChanged(ItemEvent e) {
                    if (chckbxArg.isSelected()) {
                        TFArglen.getComponent().setVisible(true);
                        TFArgsol.setVisible(true);
                        lbLenArg.setVisible(true);
                        lbSolArg.setVisible(true);
                        btnAddArg.setVisible(true);
                        for (JButton btnDel: delArgs) {
                            btnDel.setVisible(true);
                        }
                        for (IntegerTextField TFArg: TFArgs) {
                            TFArg.getComponent().setVisible(true);
                        }
                        for (JTextField TFArgSolution: TFArgsSolutions) {
                            TFArgSolution.setVisible(true);
                        }
                    } else {
                        TFArglen.getComponent().setVisible(false);
                        TFArgsol.setVisible(false);
                        lbLenArg.setVisible(false);
                        lbSolArg.setVisible(false);
                        btnAddArg.setVisible(false);
                        for (JButton btnDel: delArgs) {
                            btnDel.setVisible(false);
                        }
                        for (IntegerTextField TFArg: TFArgs) {
                            TFArg.getComponent().setVisible(false);
                        }
                        for (JTextField TFArgSolution: TFArgsSolutions) {
                            TFArgSolution.setVisible(false);
                        }
                    }
                }
            }
        );

        btnAddArg.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                IntegerTextField TFArg = addIntegerTextFieldtoPanel(ArgPanel, 1, GuiArgCounter);
                TFArgs.add(TFArg);

                JTextField TFArgSolution = addTextFieldToPanel(ArgPanel, 2, GuiArgCounter);
                TFArgSolution.setEditable(false);
                TFArgsSolutions.add(TFArgSolution);

                JButton btnDel = addButtonToPanel(delIcon, ArgPanel, 0, GuiArgCounter++);
                delArgs.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiArgCounter--;
                        ArgPanel.remove(TFArg.getComponent());
                        ArgPanel.remove(TFArgSolution);
                        ArgPanel.remove(btnDel);
                        delArgs.remove(btnDel);
                        TFArgs.remove(TFArg);
                        TFArgsSolutions.remove(TFArgSolution);
                        ArgPanel.repaint();
                        ArgPanel.revalidate();
                    }
                });
                ArgPanel.repaint();
                ArgPanel.revalidate();
            }
        });
        SAPanel.setLayout(gl_SAPanel);
    }

    private void buildCSOPanel() {
        CSOPanel = new JPanel();
        TitledBorder borderCSO = BorderFactory.createTitledBorder("Custom symbolic options");
        borderCSO.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        CSOPanel.setBorder(borderCSO);
        MemPanel = new JPanel();

        JLabel lbMemory = new JLabel("Store symbolic vector:");
        lbMemory.setHorizontalAlignment(SwingConstants.CENTER);
        lbMemory.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lbRegisters = new JLabel("<html>Registers<br/>Hint: to create and store symbolic vector enter \"sv{length}\", for example \"sv16\"</html>");
        lbRegisters.setHorizontalAlignment(SwingConstants.CENTER);
        lbRegisters.setFont(new Font("SansSerif", Font.PLAIN, 12));

        RegPanel = new JPanel();

        WMPanel = new JPanel();
        WMPanel.setBorder(null);
        GridBagLayout gbl_WMPanel = new GridBagLayout();
        gbl_WMPanel.columnWidths = new int[] {
            0,
            0,
            0
        };
        gbl_WMPanel.rowHeights = new int[] {
            0,
            0,
            0
        };
        gbl_WMPanel.columnWeights = new double[] {
            Double.MIN_VALUE,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_WMPanel.rowWeights = new double[] {
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        WMPanel.setLayout(gbl_WMPanel);

        lblWriteToMemory = new JLabel("Write to memory:");
        lblWriteToMemory.setHorizontalAlignment(SwingConstants.CENTER);
        lblWriteToMemory.setFont(new Font("SansSerif", Font.PLAIN, 12));

        lbStoreAddr = addLabelToPanel("Address", WMPanel, 1, 0);

        lbStoreVal = addLabelToPanel("Value", WMPanel, 2, 0);

        TFstore_addr = addIntegerTextFieldtoPanel(WMPanel, 1, 1);
        TFstore_addr.setHexMode();

        TFstore_val = addIntegerTextFieldtoPanel(WMPanel, 2, 1);
        TFstore_val.setHexMode();

        btnAddWM = addButtonToPanel(addIcon, WMPanel, 0, 1);
        btnAddWM.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                IntegerTextField TFaddr = addIntegerTextFieldtoPanel(WMPanel, 1, GuiStoreCounter);
                TFaddr.setHexMode();
                TFStoreAddrs.add(TFaddr);

                IntegerTextField TFval = addIntegerTextFieldtoPanel(WMPanel, 2, GuiStoreCounter);
                TFval.setHexMode();
                TFStoreVals.add(TFval);

                JButton btnDel = addButtonToPanel(delIcon, WMPanel, 0, GuiStoreCounter++);
                delStore.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        GuiStoreCounter--;
                        WMPanel.remove(TFaddr.getComponent());
                        WMPanel.remove(TFval.getComponent());
                        WMPanel.remove(btnDel);
                        delStore.remove(btnDel);
                        TFStoreAddrs.remove(TFaddr);
                        TFStoreVals.remove(TFval);
                        WMPanel.repaint();
                        WMPanel.revalidate();
                    }
                });
                WMPanel.repaint();
                WMPanel.revalidate();
            }
        });

        GroupLayout gl_CSOPanel = new GroupLayout(CSOPanel);
        gl_CSOPanel.setHorizontalGroup(
            gl_CSOPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_CSOPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(MemPanel, GroupLayout.DEFAULT_SIZE, 257, Short.MAX_VALUE)
                    .addGap(24))
                .addGroup(gl_CSOPanel.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(gl_CSOPanel.createParallelGroup(Alignment.LEADING)
                        .addGroup(gl_CSOPanel.createSequentialGroup()
                            .addComponent(lblWriteToMemory)
                            .addPreferredGap(ComponentPlacement.RELATED, 150, GroupLayout.PREFERRED_SIZE))
                        .addComponent(WMPanel, GroupLayout.DEFAULT_SIZE, 256, Short.MAX_VALUE))
                    .addGap(25))
                .addGroup(gl_CSOPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(RegPanel, GroupLayout.DEFAULT_SIZE, 251, Short.MAX_VALUE)
                    .addGap(30))
                .addGroup(gl_CSOPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbRegisters, GroupLayout.PREFERRED_SIZE, 258, GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(23, Short.MAX_VALUE))
                .addGroup(gl_CSOPanel.createSequentialGroup()
                    .addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(145, Short.MAX_VALUE))
        );
        gl_CSOPanel.setVerticalGroup(
            gl_CSOPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_CSOPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbMemory, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(MemPanel, GroupLayout.DEFAULT_SIZE, 40, Short.MAX_VALUE)
                    .addGap(23)
                    .addComponent(lblWriteToMemory)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(WMPanel, GroupLayout.DEFAULT_SIZE, 39, Short.MAX_VALUE)
                    .addGap(18)
                    .addComponent(lbRegisters)
                    .addGap(9)
                    .addComponent(RegPanel, GroupLayout.DEFAULT_SIZE, 38, Short.MAX_VALUE)
                    .addGap(54))
        );
        GridBagLayout gbl_RegPanel = new GridBagLayout();
        gbl_RegPanel.columnWidths = new int[] {
            0,
            0,
            0
        };
        gbl_RegPanel.rowHeights = new int[] {
            0,
            0
        };
        gbl_RegPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_RegPanel.rowWeights = new double[] {
            0.0,
            0.0
        };
        RegPanel.setLayout(gbl_RegPanel);

        JLabel lblReg = addLabelToPanel("Register", RegPanel, 1, 0);

        JLabel lblValue = addLabelToPanel("Value", RegPanel, 2, 0);

        TFVal1 = addTextFieldToPanel(RegPanel, 2, 1);

        TFReg1 = addTextFieldToPanel(RegPanel, 1, 1);

        JButton btnAddButton = addButtonToPanel(addIcon, RegPanel, 0, 1);
        btnAddButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                addRegisterRow();
            }
        });

        GridBagLayout gbl_MemPanel = new GridBagLayout();
        gbl_MemPanel.columnWidths = new int[] {
            0,
            0,
            0
        };
        gbl_MemPanel.rowHeights = new int[] {
            0,
            0,
            0
        };
        gbl_MemPanel.columnWeights = new double[] {
            0.0,
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_MemPanel.rowWeights = new double[] {
            0.0,
            0.0,
            0.0
        };
        MemPanel.setLayout(gbl_MemPanel);

        JButton btnAddMem = addButtonToPanel(addIcon, MemPanel, 0, 1);
        btnAddMem.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                addSSVRow();
            }
        });

        JLabel lbMemAddr = addLabelToPanel("Address", MemPanel, 1, 0);

        JLabel lblLentgh = addLabelToPanel("Length", MemPanel, 2, 0);

        JLabel lblSolution = addLabelToPanel("Solution", MemPanel, 3, 0);

        TFsymbmem_addr = addIntegerTextFieldtoPanel(MemPanel, 1, 1);
        TFsymbmem_addr.setHexMode();

        TFsymbmem_len = addIntegerTextFieldtoPanel(MemPanel, 2, 1);

        TFsymbmem_sol = addTextFieldToPanel(MemPanel, 3, 1);
        TFsymbmem_sol.setEditable(false);

        CSOPanel.setLayout(gl_CSOPanel);
    }

    private GridBagConstraints createGridbagConstraints(int gridx, int gridy) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = gridx;
        gbc.gridy = gridy;
        gbc.insets = new Insets(0, 0, 0, 5);
        gbc.weightx = 1;
        gbc.weighty = 0.1;
        return gbc;
    }

    private JTextField addTextFieldToPanel(JPanel targetPanel, int gridx, int gridy) {
        JTextField textField = new JTextField();
        GridBagConstraints gbc = createGridbagConstraints(gridx, gridy);
        targetPanel.add(textField, gbc);
        return textField;
    }

    private IntegerTextField addIntegerTextFieldtoPanel(JPanel targetPanel, int gridx, int gridy) {
        IntegerTextField textField = new IntegerTextField();
        GridBagConstraints gbc = createGridbagConstraints(gridx, gridy);
        targetPanel.add(textField.getComponent(), gbc);
        return textField;
    }

    private JLabel addLabelToPanel(String labelText, JPanel targetPanel, int gridx, int gridy) {
        JLabel label = new JLabel(labelText);
        label.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc = createGridbagConstraints(gridx, gridy);
        gbc.fill = GridBagConstraints.NONE;
        targetPanel.add(label, gbc);
        return label;
    }

    private JButton addButtonToPanel(ImageIcon icon, JPanel targetPanel, int gridx, int gridy) {
        JButton button = new JButton("");
        button.setContentAreaFilled(false);
        button.setBorder(null);
        button.setIcon(icon);
        GridBagConstraints gbc = createGridbagConstraints(gridx, gridy);
        gbc.weightx = 0;
        targetPanel.add(button, gbc);
        return button;
    }

    private void addRegisterRow() {
        JTextField TFReg = addTextFieldToPanel(RegPanel, 1, GuiRegCounter);
        TFregs.add(TFReg);

        JTextField TFVal = addTextFieldToPanel(RegPanel, 2, GuiRegCounter);
        TFVals.add(TFVal);

        JButton btnDel = addButtonToPanel(delIcon, RegPanel, 0, GuiRegCounter++);
        delButtons.add(btnDel);
        btnDel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                GuiRegCounter--;
                RegPanel.remove(TFReg);
                RegPanel.remove(TFVal);
                RegPanel.remove(btnDel);
                delButtons.remove(btnDel);
                TFregs.remove(TFReg);
                TFVals.remove(TFVal);
                RegPanel.repaint();
                RegPanel.revalidate();
            }
        });
        RegPanel.repaint();
        RegPanel.revalidate();
    }

    private void addSSVRow() {
        IntegerTextField TFaddr = addIntegerTextFieldtoPanel(MemPanel, 1, GuiMemCounter);
        TFaddr.setHexMode();
        TFAddrs.add(TFaddr);

        IntegerTextField TFlen = addIntegerTextFieldtoPanel(MemPanel, 2, GuiMemCounter);
        TFLens.add(TFlen);

        JTextField TFsol = addTextFieldToPanel(MemPanel, 3, GuiMemCounter);
        TFsol.setEditable(false);
        TFSolutions.add(TFsol);

        JButton btnDel = addButtonToPanel(delIcon, MemPanel, 0, GuiMemCounter++);
        delMem.add(btnDel);
        btnDel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                GuiMemCounter--;
                MemPanel.remove(TFaddr.getComponent());
                MemPanel.remove(TFlen.getComponent());
                MemPanel.remove(TFsol);
                MemPanel.remove(btnDel);
                delMem.remove(btnDel);
                TFAddrs.remove(TFaddr);
                TFLens.remove(TFlen);
                TFSolutions.remove(TFsol);
                MemPanel.repaint();
                MemPanel.revalidate();
            }
        });

        MemPanel.repaint();
        MemPanel.revalidate();
    }

    private void buildHookPanel() {
        HookPanel = new JPanel();
        TitledBorder borderHP = BorderFactory.createTitledBorder("Hook options");
        borderHP.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        HookPanel.setBorder(borderHP);

        JButton btnAddHook = new JButton("Add Hook");
        btnAddHook.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                HookCreation window = new HookCreation();
                window.main();
            }
        });
        btnAddHook.setFont(new Font("SansSerif", Font.PLAIN, 11));

        RegHookPanel = new JPanel();

        GroupLayout gl_HookPanel = new GroupLayout(HookPanel);
        gl_HookPanel.setHorizontalGroup(
            gl_HookPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_HookPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(btnAddHook, GroupLayout.PREFERRED_SIZE, 105, Short.MAX_VALUE)
                    .addGap(43)
                    .addComponent(RegHookPanel, GroupLayout.DEFAULT_SIZE, 105, Short.MAX_VALUE)
                    .addContainerGap())
        );
        gl_HookPanel.setVerticalGroup(
            gl_HookPanel.createParallelGroup(Alignment.TRAILING)
                .addGroup(gl_HookPanel.createSequentialGroup()
                    .addGroup(gl_HookPanel.createParallelGroup(Alignment.TRAILING)
                        .addGroup(Alignment.LEADING, gl_HookPanel.createSequentialGroup()
                            .addContainerGap()
                            .addComponent(btnAddHook))
                        .addGroup(gl_HookPanel.createSequentialGroup()
                            .addGap(10)
                            .addComponent(RegHookPanel, GroupLayout.DEFAULT_SIZE, 26, Short.MAX_VALUE)))
                    .addGap(34))
        );
        GridBagLayout gbl_RegHookPanel = new GridBagLayout();
        gbl_RegHookPanel.columnWidths = new int[] {
            0
        };
        gbl_RegHookPanel.rowHeights = new int[] {
            0
        };
        gbl_RegHookPanel.columnWeights = new double[] {
            Double.MIN_VALUE
        };
        gbl_RegHookPanel.rowWeights = new double[] {
            Double.MIN_VALUE
        };
        RegHookPanel.setLayout(gbl_RegHookPanel);
        HookPanel.setLayout(gl_HookPanel);
    }

    private void buildOutputPanel() {
        OutputPanel = new JPanel();
        TitledBorder borderOutput = BorderFactory.createTitledBorder("Output (stdout)");
        borderOutput.setTitleFont(new Font("SansSerif", Font.PLAIN, 12));
        OutputPanel.setBorder(borderOutput);

        OutputFindPanel = new JPanel();

        JLabel lbOutputFind = new JLabel("Find output:");
        lbOutputFind.setForeground(new Color(60, 179, 113));
        lbOutputFind.setFont(new Font("SansSerif", Font.PLAIN, 12));

        OutputAvoidPanel = new JPanel();

        JLabel lbOutputAvoid = new JLabel("Avoid output:");
        lbOutputAvoid.setForeground(new Color(255, 0, 0));
        lbOutputAvoid.setFont(new Font("SansSerif", Font.PLAIN, 12));

        JLabel lbOutputSolution = new JLabel("Solution output:");
        lbOutputSolution.setFont(new Font("SansSerif", Font.PLAIN, 12));

        OutputSolutionArea = new JTextArea();
        OutputSolutionArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        scrollOutputSolution = new JScrollPane(OutputSolutionArea);
        OutputSolutionArea.setEditable(false);
        scrollOutputSolution.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollOutputSolution.setBorder(new LineBorder(Color.blue, 1));

        GroupLayout gl_OutputPanel = new GroupLayout(OutputPanel);
        gl_OutputPanel.setHorizontalGroup(
            gl_OutputPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbOutputFind, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE))
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(OutputFindPanel, GroupLayout.DEFAULT_SIZE, 257, Short.MAX_VALUE))
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbOutputAvoid, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE))
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(OutputAvoidPanel, GroupLayout.DEFAULT_SIZE, 257, Short.MAX_VALUE))
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbOutputSolution, GroupLayout.PREFERRED_SIZE, 148, GroupLayout.PREFERRED_SIZE))
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(OutputSolutionArea, GroupLayout.DEFAULT_SIZE, 257, Short.MAX_VALUE))
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap(145, Short.MAX_VALUE))
        );
        gl_OutputPanel.setVerticalGroup(
            gl_OutputPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_OutputPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbOutputFind, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(OutputFindPanel, GroupLayout.DEFAULT_SIZE, 40, Short.MAX_VALUE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(lbOutputAvoid)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(OutputAvoidPanel, GroupLayout.DEFAULT_SIZE, 39, Short.MAX_VALUE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(lbOutputSolution)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(OutputSolutionArea, GroupLayout.DEFAULT_SIZE, 38, Short.MAX_VALUE)
                    .addGap(32))
        );

        GridBagLayout gbl_OutputFindPanel = new GridBagLayout();
        gbl_OutputFindPanel.columnWidths = new int[] {
            0,
            0
        };
        gbl_OutputFindPanel.rowHeights = new int[] {
            0
        };
        gbl_OutputFindPanel.columnWeights = new double[] {
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_OutputFindPanel.rowWeights = new double[] {
            0.0
        };
        OutputFindPanel.setLayout(gbl_OutputFindPanel);

        TFOutputFind1 = addTextFieldToPanel(OutputFindPanel, 1, 0);

        JButton addButton = addButtonToPanel(addIcon, OutputFindPanel, 0, 0);
        addButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                addFindOutputRow();
            }
        });

        GridBagLayout gbl_OutputAvoidPanel = new GridBagLayout();
        gbl_OutputAvoidPanel.columnWidths = new int[] {
            0,
            0
        };
        gbl_OutputAvoidPanel.rowHeights = new int[] {
            0
        };
        gbl_OutputAvoidPanel.columnWeights = new double[] {
            0.0,
            0.0,
            Double.MIN_VALUE
        };
        gbl_OutputAvoidPanel.rowWeights = new double[] {
            0.0
        };
        OutputAvoidPanel.setLayout(gbl_OutputAvoidPanel);

        TFOutputAvoid1 = addTextFieldToPanel(OutputAvoidPanel, 1, 0);

        addButton = addButtonToPanel(addIcon, OutputAvoidPanel, 0, 0);
        addButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                addAvoidOutputRow();
            }
        });

        OutputPanel.setLayout(gl_OutputPanel);
    }

    private void addFindOutputRow() {
        JTextField TFOutputFind = addTextFieldToPanel(OutputFindPanel, 1, GuiOutputFindCounter);
        TFoutputFinds.add(TFOutputFind);

        JButton btnDel = addButtonToPanel(delIcon, OutputFindPanel, 0, GuiOutputFindCounter++);
        delButtons.add(btnDel);
        btnDel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                GuiOutputFindCounter--;
                OutputFindPanel.remove(TFOutputFind);
                OutputFindPanel.remove(btnDel);
                delButtons.remove(btnDel);
                TFoutputFinds.remove(TFOutputFind);
                OutputFindPanel.repaint();
                OutputFindPanel.revalidate();
            }
        });
        OutputFindPanel.repaint();
        OutputFindPanel.revalidate();
    }

    private void addAvoidOutputRow() {
        JTextField TFOutputAvoid = addTextFieldToPanel(OutputAvoidPanel, 1, GuiOutputAvoidCounter);
        TFoutputAvoids.add(TFOutputAvoid);

        JButton btnDel = addButtonToPanel(delIcon, OutputAvoidPanel, 0, GuiOutputAvoidCounter++);
        delButtons.add(btnDel);
        btnDel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                GuiOutputAvoidCounter--;
                OutputAvoidPanel.remove(TFOutputAvoid);
                OutputAvoidPanel.remove(btnDel);
                delButtons.remove(btnDel);
                TFoutputAvoids.remove(TFOutputAvoid);
                OutputAvoidPanel.repaint();
                OutputAvoidPanel.revalidate();
            }
        });
        OutputAvoidPanel.repaint();
        OutputAvoidPanel.revalidate();
    }

    private void buildStatusPanel() {
        ImageIcon Starticon = new ImageIcon(getClass().getResource("/images/flag.png"));
        ImageIcon Stopicon = new ImageIcon(getClass().getResource("/images/process-stop.png"));

        EndPanel = new JPanel();
        EndPanel.setBorder(null);

        lbStatus = new JLabel("Status:");
        lbStatus.setForeground(Color.BLUE);
        lbStatus.setFont(new Font("SansSerif", Font.PLAIN, 13));

        StatusLabel = new JLabel("[+] Angr options selection");
        StatusLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));

        StatusLabelFound = new JLabel("");
        StatusLabelFound.setFont(new Font("SansSerif", Font.PLAIN, 12));

        btnRun = new JButton("Run");
        btnRun.setIcon(Starticon);
        btnRun.setFont(new Font("SansSerif", Font.PLAIN, 12));

        ErrorArea = new JTextArea();
        ErrorArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        scrollError = new JScrollPane(ErrorArea);
        ErrorArea.setEditable(false);
        scrollError.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollError.setBorder(new LineBorder(Color.blue, 1));
        scrollError.setVisible(false);

        ResultArea = new JTextArea();
        ResultArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        scrollResult = new JScrollPane(ResultArea);
        ResultArea.setEditable(false);
        scrollResult.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollResult.setBorder(new LineBorder(Color.blue, 1));
        scrollResult.setVisible(false);

        btnRun.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                StatusLabel.setText("[+] Angr options selection");
                resetSolutions();
                StatusLabelFound.setText("");
                isTerminated = false;
                File angrfile = saveAngrOptions(TmpDir + "angr_options.json");
                if (angrfile != null) {
                    ANGRinProgress(angrfile);
                }
            }
        });

        btnStop = new JButton("Stop");
        btnStop.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (new File(TmpDir + "angr_options.json").exists()) {
                    isTerminated = true;
                    StatusLabel.setText("[+] Stopping...");
                    StatusLabelFound.setText("");
                    scrollError.setVisible(false);
                    scrollResult.setVisible(false);
                }
            }
        });
        btnStop.setFont(new Font("SansSerif", Font.PLAIN, 12));
        btnStop.setIcon(Stopicon);

        btnImport = new JButton("Import");
        btnImport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                final JFileChooser fc = new JFileChooser();
                int result = fc.showOpenDialog(btnImport);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fc.getSelectedFile();
                    System.out.println("Selected file: " + selectedFile.getAbsolutePath());
                }
            }
        });
        btnImport.setFont(new Font("SansSerif", Font.PLAIN, 12));
        btnImport.setIcon(Stopicon);

        btnExport = new JButton("Export");
        btnExport.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                final JFileChooser fc = new JFileChooser();
                int result = fc.showOpenDialog(btnImport);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fc.getSelectedFile();
                    String path = selectedFile.getAbsolutePath();
                    File angrFile = saveAngrOptions(path);
                    if (angrFile != null) {
                        StatusLabel.setText("[+] Exported config to " + path);
                    } else {
                        StatusLabel.setText("[X] Failed to save config to " + path);
                    }
                }
            }
        });
        btnExport.setFont(new Font("SansSerif", Font.PLAIN, 12));
        btnExport.setIcon(Stopicon);

        GroupLayout gl_EndPanel = new GroupLayout(EndPanel);
        gl_EndPanel.setHorizontalGroup(
            gl_EndPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGap(10)
                    .addComponent(StatusLabelFound, GroupLayout.DEFAULT_SIZE, 127, Short.MAX_VALUE))
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGap(10)
                    .addComponent(scrollResult, GroupLayout.DEFAULT_SIZE, 378, Short.MAX_VALUE))
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGap(10)
                    .addComponent(scrollError, GroupLayout.DEFAULT_SIZE, 378, Short.MAX_VALUE))
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.TRAILING)
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addGap(134)
                            .addComponent(btnRun, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(77)
                            .addComponent(btnStop, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(77)
                            .addComponent(btnImport, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(77)
                            .addComponent(btnExport, GroupLayout.DEFAULT_SIZE, 116, Short.MAX_VALUE)
                            .addGap(62))
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addGap(10)
                            .addComponent(StatusLabel, GroupLayout.DEFAULT_SIZE, 495, Short.MAX_VALUE)))
                    .addGap(91))
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 46, GroupLayout.PREFERRED_SIZE)
                    .addContainerGap(538, Short.MAX_VALUE))
        );
        gl_EndPanel.setVerticalGroup(
            gl_EndPanel.createParallelGroup(Alignment.LEADING)
                .addGroup(gl_EndPanel.createSequentialGroup()
                    .addGap(10)
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.BASELINE)
                        .addComponent(btnRun, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnStop, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnImport, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE)
                        .addComponent(btnExport, GroupLayout.PREFERRED_SIZE, 21, GroupLayout.PREFERRED_SIZE))
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(lbStatus, GroupLayout.PREFERRED_SIZE, 13, GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(ComponentPlacement.RELATED)
                    .addComponent(StatusLabel, GroupLayout.PREFERRED_SIZE, 17, GroupLayout.PREFERRED_SIZE)
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.LEADING)
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addGap(5)
                            .addComponent(StatusLabelFound, GroupLayout.PREFERRED_SIZE, 15, GroupLayout.PREFERRED_SIZE)))
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.LEADING)
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addPreferredGap(ComponentPlacement.RELATED)
                            .addComponent(scrollResult, GroupLayout.DEFAULT_SIZE, 48, Short.MAX_VALUE)))
                    .addGroup(gl_EndPanel.createParallelGroup(Alignment.LEADING)
                        .addGroup(gl_EndPanel.createSequentialGroup()
                            .addPreferredGap(ComponentPlacement.RELATED)
                            .addComponent(scrollError, GroupLayout.DEFAULT_SIZE, 48, Short.MAX_VALUE)))
                    .addContainerGap())
        );
        EndPanel.setLayout(gl_EndPanel);
    }

    private void buildPanel() {
        panel = new JPanel();
        panel.setMinimumSize(new Dimension(210, 510));
        setVisible(true);

        addIcon = new ImageIcon(getClass().getResource("/images/add.png"));
        delIcon = new ImageIcon(getClass().getResource("/images/edit-delete.png"));
        delButtons = new ArrayList < JButton > ();
        delArgs = new ArrayList < JButton > ();
        delMem = new ArrayList < JButton > ();
        delStore = new ArrayList < JButton > ();
        delHooks = new ArrayList < JButton > ();
        TFregs = new ArrayList < JTextField > ();
        TFVals = new ArrayList < JTextField > ();
        TFArgs = new ArrayList < IntegerTextField > ();
        TFArgsSolutions = new ArrayList < JTextField > ();
        TFAddrs = new ArrayList < IntegerTextField > ();
        TFLens = new ArrayList < IntegerTextField > ();
        TFSolutions = new ArrayList < JTextField > ();
        TFStoreAddrs = new ArrayList < IntegerTextField > ();
        TFStoreVals = new ArrayList < IntegerTextField > ();
        TFoutputFinds = new ArrayList < JTextField > ();
        TFoutputAvoids = new ArrayList < JTextField > ();
        Hook = new HashMap < String[], String[][] > ();
        lbHooks = new ArrayList < JLabel > ();
        isTerminated = false;
        GuiArgCounter = 2;
        GuiMemCounter = 2;
        GuiRegCounter = 2;
        GuiStoreCounter = 2;
        GuiHookCounter = 2;
        GuiOutputFindCounter = 1;
        GuiOutputAvoidCounter = 1;
        TmpDir = System.getProperty("java.io.tmpdir");
        if (System.getProperty("os.name").contains("Windows") == false) {
            TmpDir += "/";
        }

        buildMPOPanel();
        buildArgumentsPanel();
        buildHookPanel();
        buildCSOPanel();
        buildOutputPanel();
        buildStatusPanel();

        GroupLayout gl_panel = new GroupLayout(panel);
        gl_panel.setHorizontalGroup(
            gl_panel.createParallelGroup(Alignment.TRAILING)
            .addGroup(gl_panel.createSequentialGroup()
                .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_panel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(EndPanel, GroupLayout.DEFAULT_SIZE, 550, Short.MAX_VALUE))
                    .addGroup(gl_panel.createSequentialGroup()
                        .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_panel.createSequentialGroup()
                                .addGap(10)
                                .addComponent(MPOPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE))
                            .addGroup(gl_panel.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(SAPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE))
                            .addGroup(gl_panel.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(HookPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE)))
                        .addPreferredGap(ComponentPlacement.RELATED)
                        .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_panel.createSequentialGroup()
                                .addGap(10)
                                .addComponent(CSOPanel, GroupLayout.DEFAULT_SIZE, 269, Short.MAX_VALUE))
                            .addGroup(gl_panel.createSequentialGroup()
                                .addGap(10)
                                .addComponent(OutputPanel, GroupLayout.DEFAULT_SIZE, 275, Short.MAX_VALUE)))))
            .addGap(13))
        );
        gl_panel.setVerticalGroup(
            gl_panel.createParallelGroup(Alignment.LEADING)
            .addGroup(gl_panel.createSequentialGroup()
                .addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
                    .addGroup(gl_panel.createSequentialGroup()
                        .addGap(10)
                        .addComponent(MPOPanel, GroupLayout.DEFAULT_SIZE, 178, Short.MAX_VALUE)
                        .addGap(2)
                        .addComponent(SAPanel, GroupLayout.DEFAULT_SIZE, 81, Short.MAX_VALUE)
                        .addPreferredGap(ComponentPlacement.RELATED)
                        .addComponent(HookPanel, GroupLayout.DEFAULT_SIZE, 90, Short.MAX_VALUE))
                    .addGroup(gl_panel.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(CSOPanel, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
                        .addComponent(OutputPanel, GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)))
                .addPreferredGap(ComponentPlacement.UNRELATED)
                .addComponent(EndPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addGap(5))
        );

        panel.setLayout(gl_panel);
    }

    private File saveAngrOptions(String path) {
        angr_options = collectAngrOptions();
        File angrfile = null;

        if (angr_options != null) {
            angrfile = new File(path);
            if (angrfile.exists()) {
                angrfile.delete();
            }
            try {
                FileWriter file = new FileWriter(path);
                file.write(angr_options.toString());
                file.flush();
                file.close();
            } catch (Exception e1) {};
        }
        return angrfile;
    }

    private JSONObject collectAngrOptions() {
        angr_options = new JSONObject();

        Boolean auto_load_libs = false;
        if (chckbxAutoloadlibs.isSelected()) {
            auto_load_libs = true;
        }

        angr_options.put("auto_load_libs", auto_load_libs);

        if (chckbxBlankState.isSelected()) {
            if (TFBlankState.getText().matches("0x[0-9A-Fa-f]+") == false) {
                TFBlankState.setBorder(new LineBorder(Color.red, 1));
                StatusLabel.setText("[-] Error: please, enter the correct hex value.");
                return null;
            }
            String blank_state = TFBlankState.getText();
            angr_options.put("blank_state", blank_state);
        }

        if (TFFind.getText().matches("0x[0-9A-Fa-f]+") == false) {
            TFFind.setBorder(new LineBorder(Color.red, 1));
            StatusLabel.setText("[-] Error: please, enter the correct hex value without spaces.");
            return null;
        }
        String find = TFFind.getText();
        angr_options.put("find", find);

        if (chckbxAvoidAddresses.isSelected()) {
            if (textArea.getText().replaceAll("\\s+", "").matches("[0x0-9a-fA-F, /,]+") == false) {
                textArea.setBorder(new LineBorder(Color.red, 1));
                StatusLabel.setText("[-] Error: please, enter the correct hex values separated by comma.");
                return null;
            }
            textArea.setBorder(UIManager.getLookAndFeel().getDefaults().getBorder("TextArea.border"));
            String avoid = textArea.getText().replaceAll("\\s+", "");
            angr_options.put("avoid", avoid);
        }

        if (chckbxArg.isSelected()) {
            if (TFArglen.getText().isEmpty() == false) {

                JSONObject ArgDetails = new JSONObject();
                ArgDetails.put("1", TFArglen.getText());
                for (int i = 0; i < TFArgs.size(); i++) {
                    if (TFArglen.getText().isEmpty() == false) {
                        ArgDetails.put(Integer.toString(i + 2), TFArglen.getText());
                    }
                }
                angr_options.put("Arguments", ArgDetails);
            }
        }

        if (TFsymbmem_addr.getText().isEmpty() == false & TFsymbmem_len.getText().isEmpty() == false) {

            JSONObject MemDetails = new JSONObject();
            MemDetails.put(TFsymbmem_addr.getText(), TFsymbmem_len.getText());
            for (int i = 0; i < TFAddrs.size(); i++) {
                if (TFAddrs.get(i).getText().isEmpty() == false & TFLens.get(i).getText().isEmpty() == false) {
                    MemDetails.put(TFAddrs.get(i).getText(), TFLens.get(i).getText());
                }
            }
            angr_options.put("Memory", MemDetails);
        }

        if (TFstore_addr.getText().isEmpty() == false & TFstore_val.getText().isEmpty() == false) {

            JSONObject MemStoreDetails = new JSONObject();
            MemStoreDetails.put(TFstore_addr.getText(), TFstore_val.getText());
            for (int i = 0; i < TFStoreAddrs.size(); i++) {
                if (TFStoreAddrs.get(i).getText().isEmpty() == false & TFStoreVals.get(i).getText().isEmpty() == false) {
                    MemStoreDetails.put(TFStoreAddrs.get(i).getText(), TFStoreVals.get(i).getText());
                }
            }
            angr_options.put("Store", MemStoreDetails);
        }

        if (TFReg1.getText().isEmpty() == false & TFVal1.getText().isEmpty() == false & (TFVal1.getText().matches("0x[0-9A-Fa-f]+") == true ||
                TFVal1.getText().matches("[0-9]+") == true || TFVal1.getText().contains("sv"))) {

            JSONObject RegDetails = new JSONObject();
            RegDetails.put(TFReg1.getText(), TFVal1.getText());
            for (int i = 0; i < TFregs.size(); i++) {
                if (TFregs.get(i).getText().isEmpty() == false & TFVals.get(i).getText().isEmpty() == false & (TFVals.get(i).getText().matches("0x[0-9A-Fa-f]+") == true ||
                        TFVals.get(i).getText().matches("[0-9]+") == true || TFVals.get(i).getText().contains("sv"))) {
                    RegDetails.put(TFregs.get(i).getText(), TFVals.get(i).getText());
                }
            }
            angr_options.put("Registers", RegDetails);
        }

        if (Hook.isEmpty() == false) {
            JSONArray HookList = new JSONArray();
            for (Entry < String[], String[][] > entry: Hook.entrySet()) {
                JSONObject HookDetails = new JSONObject();
                String[] HookOptions = entry.getKey();
                String HookAddress = HookOptions[0];
                HookDetails.put("Length", HookOptions[1]);
                String[][] Regs = entry.getValue();
                for (int i = 0; i < Regs[0].length; i++) {
                    if (Regs[0][i] != null & Regs[1][i] != null) {
                        HookDetails.put(Regs[0][i], Regs[1][i]);
                    }
                }
                JSONObject NewHook = new JSONObject();
                NewHook.put(HookAddress, HookDetails);
                HookList.put(NewHook);
            }
            angr_options.put("Hooks", HookList);
        }

        if (TFOutputFind1.getText().isEmpty() == false) {
            JSONArray OutputFindDetails = new JSONArray();
            OutputFindDetails.put(TFOutputFind1.getText());
            for (int i = 0; i < TFoutputFinds.size(); i++) {
                if (TFoutputFinds.get(i).getText().isEmpty() == false) {
                    OutputFindDetails.put(TFoutputFinds.get(i).getText());
                }
            }
            angr_options.put("find_output", OutputFindDetails);
        }

        if (TFOutputAvoid1.getText().isEmpty() == false) {
            JSONArray OutputAvoidDetails = new JSONArray();
            OutputAvoidDetails.put(TFOutputAvoid1.getText());
            for (int i = 0; i < TFoutputAvoids.size(); i++) {
                if (TFoutputAvoids.get(i).getText().isEmpty() == false) {
                    OutputAvoidDetails.put(TFoutputAvoids.get(i).getText());
                }
            }
            angr_options.put("avoid_output", OutputAvoidDetails);
        }

        String binary_path = ThisProgram.getExecutablePath();

        if (System.getProperty("os.name").contains("Windows")) {
            binary_path = binary_path.replaceFirst("/", "");
            binary_path = binary_path.replace("/", "\\");
        }
        angr_options.put("binary_file", binary_path);

            if (ThisProgram.getExecutableFormat().contains("Raw Binary")) {
            JSONObject RawBinary= new JSONObject();
            String Arch = ThisProgram.getLanguage().toString().substring(0, ThisProgram.getLanguage().toString().indexOf("/"));
            RawBinary.put("Arch", Arch);
            RawBinary.put("Base", "0x" + Long.toHexString(ThisProgram.getMinAddress().getOffset()));
            angr_options.put("Raw Binary", RawBinary);
        }
        panel.revalidate();

        return angr_options;
    }

    protected void ANGRinProgress(File angrfile) {

        SwingWorker sw = new SwingWorker() {
            @Override
            protected String doInBackground() throws Exception {

                String spath = null;
                try {
                    spath = new File(AngryGhidraProvider.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath();
                } catch (URISyntaxException e2) {
                    e2.printStackTrace();
                }
                spath = (spath.substring(0, spath.indexOf("lib")) + "angryghidra_script" + File.separator + "angryghidra.py");
                File Scriptfile = new File(spath);
                String script_path = Scriptfile.getAbsolutePath();

                //PythonVersion check (issue#5)
                if (runAngr("python3", script_path, angrfile.getAbsolutePath()) == 0) {
                    ProcessBuilder pb = new ProcessBuilder("python", "--version");
                    try {
                        Process p = pb.start();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                        String line = "";
                        while ((line = reader.readLine()) != null) {
                            if (compareVersion(line.substring(7), "3.4") == -1 && compareVersion(line.substring(7), "3.0") == 1) {
                                runAngr("python", script_path, angrfile.getAbsolutePath());
                            }
                        };
                        p.waitFor();
                        reader.close();
                    } catch (Exception e1) {
                        e1.printStackTrace();
                    };
                }
                angrfile.delete();
                return null;
            }

            private void setArgvSolution(JSONObject solutionObject) {
                JSONArray argv = solutionObject.getJSONArray("argv");
                if (argv != null && argv.isEmpty() == false) {
                    for (int i=0; i < argv.length(); ++i) {
                        TFArgsSolutions.get(i).setText(argv.getString(i));
                    }
                }
            }

            private void setMemorySolutions(JSONObject solutionObject) {
                if (solutionObject.has("memory")) {
                    JSONObject memorySolutions = solutionObject.getJSONObject("memory");
                    memorySolutions.keySet().forEach(address -> {
                        String solution = memorySolutions.getString(address);
                        if (TFsymbmem_addr.getText().equals(address)) {
                            TFsymbmem_sol.setText(solution);
                        }
                        for (int i = 0; i < TFAddrs.size(); i++) {
                            if (TFAddrs.get(i).getText().equals(address)) {
                                TFSolutions.get(i).setText(solution);
                            }
                        }
                    });
                }
            }

            private void setOutputSolution(JSONObject solutionObject) {
                String stdout = solutionObject.getString("stdout");
                if (stdout != null) {
                    OutputSolutionArea.setText(stdout.trim());
                }
            }

            @Override
            protected void done() {
                if (isTerminated == true) {
                    StatusLabel.setText("[+] Angr options selection");
                    return;
                }

                if (angrError != null && angrError.isEmpty() == false) {
                    StatusLabelFound.setText("[X] Error during angr execution:");
                    scrollError.setVisible(true);
                    ErrorArea.setText(angrError.trim());
                }
                if (solutionObject != null) {
                    scrollResult.setVisible(true);
                    ResultArea.setText(solution);
                    if (solutionObject.isEmpty()) {
                        StatusLabelFound.setText("[-] Solution NOT found!");
                        OutputSolutionArea.setText("[-] Solution NOT found!");
                    } else {
                        StatusLabelFound.setText("[+] Solution found:");
                        if (insntrace != null && insntrace.isEmpty() == false) {
                            List < String > TraceList = Arrays.asList(insntrace.split("\\s*,\\s*"));
                            for (String TraceAddress: TraceList) {
                                AddressFactory AF = ThisProgram.getAddressFactory();
                                try {
                                    AngryGhidraPopupMenu.SetColor(AF.getAddress(TraceAddress), Color.getHSBColor(247, 224, 98));
                                } catch (Exception ex) {};
                            }
                        }

                        setArgvSolution(solutionObject);
                        setMemorySolutions(solutionObject);
                        setOutputSolution(solutionObject);
                    }
                }
            }
        };
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                StatusLabel.setText("[+] Angr in progress...");
                scrollError.setVisible(false);
            }
        });
        sw.execute();
    }

    public int runAngr(String pythonVersion, String script_path, String angrfile_path) {
        solution = "";
        insntrace = "";
        angrError = "";
        ProcessBuilder pb = new ProcessBuilder(pythonVersion, script_path, angrfile_path);
        try {
            Process p = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = "";
            while ((line = reader.readLine()) != null & isTerminated == false) {
                solution += line + "\n";
            };
            if (isTerminated == true) {
                p.destroy();
                reader.close();
                return -1;
            }
            reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            while ((line = reader.readLine()) != null) {
                angrError += line + "\n";
            }
            p.waitFor();
            reader.close();
            solutionObject = new JSONObject(solution);
            insntrace = solutionObject.getString("trace");
            return 1;
        } catch (Exception e1) {
            e1.printStackTrace();
            return 0;
        }
    }

    public int compareVersion(String version1, String version2) {
        String[] arr1 = version1.split("\\.");
        String[] arr2 = version2.split("\\.");

        int i=0;
        while(i<arr1.length || i<arr2.length){
            if(i<arr1.length && i<arr2.length){
                if(Integer.parseInt(arr1[i]) < Integer.parseInt(arr2[i])){
                    return -1;
                }else if(Integer.parseInt(arr1[i]) > Integer.parseInt(arr2[i])){
                    return 1;
                }
            } else if(i<arr1.length){
                if(Integer.parseInt(arr1[i]) != 0){
                    return 1;
                }
            } else if(i<arr2.length){
               if(Integer.parseInt(arr2[i]) != 0){
                    return -1;
                }
            }
            i++;
        }
        return 0;
    }

    private void resetSolutions() {
        // reset arguments panel
        for (JTextField TFArgSolution: TFArgsSolutions) {
            TFArgSolution.setText("");
        }

        // reset output panel
        OutputSolutionArea.setText("");

        // status panel
        StatusLabelFound.setText("");
        scrollResult.setVisible(false);
        ResultArea.setText("");
        scrollError.setVisible(false);
        ErrorArea.setText("");
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    public void setProgram(Program p) {
        ThisProgram = p;
    }
}
